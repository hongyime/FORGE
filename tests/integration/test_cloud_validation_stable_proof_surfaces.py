from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.deterministic_findings import DeterministicFindingEngine
from forge.phase4.attack_path import AttackGraphBuilder
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer
from forge.reporting.dashboard import generate_dashboard
from forge.utils.cloud_exposure_gate import is_reportable_cloud_validation
from forge.webui.app import create_app
from forge.webui.auth import mint_token

ENGAGEMENT_ID = 1001

STABLE_FIREBASE = "stable-firebase-prod"
WEAK_FIREBASE = "weak-firebase-lab"
STABLE_BUCKET = "stable-report-bucket"
PLACEHOLDER_BUCKET = "placeholder-report-bucket"
HONEYPOT_SUPABASE = "honeypotbase"
WEAK_KEY_TARGET = f"artifact://{WEAK_FIREBASE}/app.js"
HONEYPOT_KEY_TARGET = f"artifact://{HONEYPOT_SUPABASE}/app.js"


def test_stable_proof_gate_filters_validated_looking_cloud_rows_across_surfaces(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "test-secret")
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    data_dir, reports_dir, db_path = _build_fixture(tmp_path)

    _assert_gate_helper_contract()
    _assert_phase6_report_surface_filters_stale_rows(db_path, reports_dir)
    _assert_attack_graph_filters_stale_rows(db_path)
    slug = _assert_dashboard_filters_stale_rows(data_dir, reports_dir)
    _assert_api_filters_stale_rows(slug)
    _assert_deterministic_engine_removes_unstable_findings(db_path)


def _build_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    db_root = data_dir / "engagements"
    db_root.mkdir(parents=True)
    reports_dir.mkdir()
    db_path = db_root / f"{ENGAGEMENT_ID}.db"

    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        run_migrations(con)
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Stable Proof Gate', '["stable-proof.example"]', 'ACTIVE', 'tester')
            """,
            (ENGAGEMENT_ID,),
        )
        for asset_type, identifier in (
            ("firebase", STABLE_FIREBASE),
            ("firebase", WEAK_FIREBASE),
            ("aws_s3", STABLE_BUCKET),
            ("aws_s3", PLACEHOLDER_BUCKET),
            ("supabase", HONEYPOT_SUPABASE),
        ):
            con.execute(
                """
                INSERT INTO cloud_assets
                    (engagement_id, asset_type, identifier, provider_identifier, source)
                VALUES (?, ?, ?, ?, 'test_fixture')
                """,
                (ENGAGEMENT_ID, asset_type, identifier, identifier),
            )
        validation_rows = [
            (
                "firebase",
                STABLE_FIREBASE,
                "VALIDATED",
                "firebase_database_shallow_read",
                200,
                "Live records observed: users/prod records=2",
                "Live records observed",
            ),
            (
                "firebase",
                WEAK_FIREBASE,
                "VALIDATED",
                "firebase_database_shallow_read",
                200,
                '{"dummy":true,"sample":"test data","placeholder":"changeme"}',
                "mock provider placeholder response",
            ),
            (
                "aws_s3",
                STABLE_BUCKET,
                "VALIDATED",
                "s3_list_bucket",
                200,
                (
                    "<ListBucketResult><Contents><Key>reports/customer-data.csv</Key>"
                    "</Contents></ListBucketResult>"
                ),
                "real object metadata observed",
            ),
            (
                "aws_s3",
                PLACEHOLDER_BUCKET,
                "VALIDATED",
                "s3_list_bucket",
                200,
                (
                    "<ListBucketResult><Contents><Key>sample/test-data.json</Key>"
                    "</Contents></ListBucketResult>"
                ),
                "placeholder sample listing",
            ),
            (
                "supabase",
                HONEYPOT_SUPABASE,
                "HONEYPOT_SUSPECTED",
                "supabase_rest_root",
                200,
                '{"sample":"test data","placeholder":"changeme"}',
                "honeypot placeholder response",
            ),
        ]
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, provider_identifier,
                 validation_status, validation_method, http_status, evidence, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (ENGAGEMENT_ID, asset_type, identifier, identifier, status, method, http, evidence, notes)
                for asset_type, identifier, status, method, http, evidence, notes in validation_rows
            ],
        )
        _insert_stale_finding(con, "firebase", STABLE_FIREBASE)
        _insert_stale_finding(con, "firebase", WEAK_FIREBASE)
        _insert_stale_finding(con, "aws_s3", STABLE_BUCKET)
        _insert_stale_finding(con, "aws_s3", PLACEHOLDER_BUCKET)
        _insert_stale_finding(con, "supabase", HONEYPOT_SUPABASE)
        _insert_stale_key_finding(
            con,
            "firebase",
            WEAK_FIREBASE,
            WEAK_KEY_TARGET,
            "firebase_database_shallow_read",
            "Firebase project reference responded with non-empty data.",
        )
        _insert_stale_key_finding(
            con,
            "supabase",
            HONEYPOT_SUPABASE,
            HONEYPOT_KEY_TARGET,
            "supabase_rest_root",
            "Supabase REST endpoint returned live data.",
        )
        _insert_stale_graph_snapshot(con)
        con.commit()
    finally:
        con.close()
    return data_dir, reports_dir, db_path


def _insert_stale_finding(
    con: sqlite3.Connection,
    asset_type: str,
    identifier: str,
) -> None:
    provider = {
        "aws_s3": "aws",
        "firebase": "firebase",
        "supabase": "supabase",
    }[asset_type]
    title = {
        "aws_s3": "Validated public S3 bucket listing exposure",
        "firebase": "Validated Firebase data exposure",
        "supabase": "Validated Supabase data exposure",
    }[asset_type]
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (engagement_id, vuln_type, target_url, parameter, severity, title,
             description, evidence, cloud_provider, resource_id,
             compliance_control, remediation_cli)
        VALUES (?, 'DETERMINISTIC_CLOUD_EXPOSURE', ?, ?, 'HIGH', ?, ?, ?, ?, ?,
                'ACCESS_CONTROL', 'review cloud access policy')
        """,
        (
            ENGAGEMENT_ID,
            f"{asset_type}://{identifier}",
            asset_type,
            title,
            f"Stale finding row for {identifier}",
            "stale finding evidence",
            provider,
            identifier,
        ),
    )


def _insert_stale_key_finding(
    con: sqlite3.Connection,
    asset_type: str,
    identifier: str,
    target_url: str,
    method: str,
    proof: str,
) -> None:
    validation_detail = f"VALIDATED:{method}:{proof}"
    con.execute(
        """
        INSERT INTO key_scanner_findings
            (engagement_id, domain, service, pattern_name, source_backend,
             source_url, repo_name, key_redacted, validation_state,
             validation_detail)
        VALUES (?, ?, ?, ?, 'artifact', ?, 'app.js', 'KEY...TEST',
                'ACTIVE', ?)
        """,
        (
            ENGAGEMENT_ID,
            identifier,
            asset_type,
            f"{asset_type}_api_key",
            target_url,
            validation_detail,
        ),
    )
    con.execute(
        """
        INSERT INTO vulnerability_findings
            (engagement_id, vuln_type, target_url, parameter, severity, title,
             description, evidence, cloud_provider, resource_id,
             compliance_control, remediation_cli)
        VALUES (?, 'DETERMINISTIC_KEY_EXPOSURE', ?, ?, 'HIGH', ?, ?, ?, ?, ?,
                'SECRET_MANAGEMENT', 'rotate exposed key')
        """,
        (
            ENGAGEMENT_ID,
            target_url,
            f"{asset_type}:{asset_type}_api_key",
            f"Validated exposed {asset_type} credential reference",
            f"Stale key exposure row for {identifier}",
            f"validation={validation_detail}",
            {
                "firebase": "firebase",
                "supabase": "supabase",
            }[asset_type],
            identifier,
        ),
    )


def _insert_stale_graph_snapshot(con: sqlite3.Connection) -> None:
    graph = {
        "nodes": [
            {
                "node_id": "VULN::weak-key",
                "node_type": "VULN",
                "label": "Validated exposed firebase credential reference",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_KEY_EXPOSURE",
                    "validation_asset_type": "firebase",
                    "resource_id": WEAK_FIREBASE,
                    "validation_status": "VALIDATED",
                    "validation_method": "firebase_database_shallow_read",
                    "validation_proof": "Firebase project reference responded with non-empty data.",
                },
            },
            {
                "node_id": "VULN::honeypot-key",
                "node_type": "VULN",
                "label": "Validated exposed supabase credential reference",
                "source_table": "vulnerability_findings",
                "metadata": {
                    "vuln_type": "DETERMINISTIC_KEY_EXPOSURE",
                    "validation_asset_type": "supabase",
                    "resource_id": HONEYPOT_SUPABASE,
                    "validation_status": "VALIDATED",
                    "validation_method": "supabase_rest_root",
                    "validation_proof": "Supabase REST endpoint returned live data.",
                },
            },
            {
                "node_id": "CLOUD::weak-firebase",
                "node_type": "CLOUD",
                "label": WEAK_FIREBASE,
                "source_table": "cloud_assets",
                "metadata": {
                    "service": "firebase",
                    "identifier": WEAK_FIREBASE,
                    "validation_status": "VALIDATED",
                    "validation_method": "firebase_database_shallow_read",
                },
            },
        ],
        "edges": [
            {
                "source_node_id": "VULN::weak-key",
                "target_node_id": "CLOUD::weak-firebase",
            }
        ],
        "critical_path_nodes": ["VULN::weak-key", "CLOUD::weak-firebase"],
    }
    con.execute(
        """
        INSERT INTO attack_graph_snapshots
            (engagement_id, snapshot_at, node_count, edge_count,
             critical_path_weight, min_severity, pruned, graph_json,
             mermaid_output, dot_output)
        VALUES (?, '2026-07-24T00:00:00Z', 3, 1, 90.0, 'LOW', 0, ?, '', '')
        """,
        (ENGAGEMENT_ID, json.dumps(graph, sort_keys=True)),
    )


def _assert_gate_helper_contract() -> None:
    assert is_reportable_cloud_validation(
        "firebase",
        "VALIDATED",
        "firebase_database_shallow_read",
        evidence="Live records observed: users/prod records=2",
        require_stable_proof=True,
    )
    assert not is_reportable_cloud_validation(
        "firebase",
        "VALIDATED",
        "firebase_database_shallow_read",
        evidence='{"dummy":true,"sample":"test data","placeholder":"changeme"}',
        notes="mock provider placeholder response",
        require_stable_proof=True,
    )
    assert not is_reportable_cloud_validation(
        "aws_s3",
        "VALIDATED",
        "s3_list_bucket",
        evidence="<ListBucketResult><Contents><Key>sample/test-data.json</Key></Contents></ListBucketResult>",
        notes="placeholder sample listing",
        require_stable_proof=True,
    )
    assert not is_reportable_cloud_validation(
        "supabase",
        "HONEYPOT_SUSPECTED",
        "supabase_rest_root",
        evidence="Live records observed",
        require_stable_proof=True,
    )


def _assert_phase6_report_surface_filters_stale_rows(
    db_path: Path,
    reports_dir: Path,
) -> None:
    ctx = ContextBuilder(db_path, ENGAGEMENT_ID).build()
    assert _finding_targets(ctx.exploits.exploited) == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }

    report_path = ReportSynthesizer(
        db_path,
        output_dir=reports_dir,
        assume_yes=True,
        provider="template",
        max_correction_loops=0,
    ).generate(ENGAGEMENT_ID)
    report_text = report_path.read_text(encoding="utf-8")
    payload = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    exported_findings = payload["context"]["exploits"]["exploited"]
    assert _finding_targets(exported_findings) == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }
    assert f"firebase://{WEAK_FIREBASE}" not in report_text
    assert f"aws_s3://{PLACEHOLDER_BUCKET}" not in report_text
    assert f"supabase://{HONEYPOT_SUPABASE}" not in report_text
    assert WEAK_KEY_TARGET not in report_text
    assert HONEYPOT_KEY_TARGET not in report_text
    inventory = payload["context"]["cloud_validation_inventory"]
    assert _inventory_status(inventory, "firebase", WEAK_FIREBASE) == "UNVERIFIED"
    assert _inventory_stored_status(inventory, "firebase", WEAK_FIREBASE) == "VALIDATED"
    assert _inventory_status(inventory, "aws_s3", PLACEHOLDER_BUCKET) == "UNVERIFIED"
    assert _inventory_stored_status(inventory, "aws_s3", PLACEHOLDER_BUCKET) == "VALIDATED"
    assert _inventory_status(inventory, "supabase", HONEYPOT_SUPABASE) == "HONEYPOT_SUSPECTED"

    with report_path.with_suffix(".csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    finding_targets = {row["target_url"] for row in rows if row.get("record_type") == "finding"}
    assert finding_targets == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }
    validation_rows = [row for row in rows if row.get("record_type") == "cloud_validation"]
    assert _csv_validation_status(validation_rows, "firebase", WEAK_FIREBASE) == "UNVERIFIED"
    assert _csv_stored_validation_status(validation_rows, "firebase", WEAK_FIREBASE) == "VALIDATED"
    assert _csv_validation_status(validation_rows, "supabase", HONEYPOT_SUPABASE) == "HONEYPOT_SUSPECTED"


def _assert_attack_graph_filters_stale_rows(db_path: Path) -> None:
    graph = AttackGraphBuilder(engagement_id=ENGAGEMENT_ID, db_path=db_path).build()
    vuln_targets = {
        str(node.metadata.get("target_url") or "")
        for node in graph.nodes
        if node.source_table == "vulnerability_findings"
    }
    assert vuln_targets == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }
    cloud_metadata = {
        str(node.metadata.get("provider_identifier") or ""): node.metadata
        for node in graph.nodes
        if node.source_table == "cloud_assets"
    }
    assert cloud_metadata[WEAK_FIREBASE]["validation_reportable"] is False
    assert cloud_metadata[PLACEHOLDER_BUCKET]["validation_reportable"] is False
    assert cloud_metadata[HONEYPOT_SUPABASE]["validation_status"] == "HONEYPOT_SUSPECTED"


def _assert_dashboard_filters_stale_rows(data_dir: Path, reports_dir: Path) -> str:
    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )
    overview = json.loads((reports_dir / "dashboard" / "data" / "engagements.json").read_text(encoding="utf-8"))
    slug = next(item["slug"] for item in overview["items"] if item["id"] == str(ENGAGEMENT_ID))
    detail = json.loads(
        (
            reports_dir
            / "dashboard"
            / "data"
            / "engagements"
            / f"{slug}.json"
        ).read_text(encoding="utf-8")
    )
    assert _dashboard_targets(detail) == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }
    assert detail["severity_summary"]["HIGH"] == 2
    assert detail["counts"]["key_scanner_findings"] == 0
    assert detail["sections"]["key_scanner_findings"] == []
    _assert_graph_payload_excludes_stale_key_nodes(detail)
    validation_rows = {
        (row["Type"], row["Asset"]): row["Status"]
        for row in detail["sections"]["cloud_validation_results"]
    }
    assert validation_rows[("firebase", WEAK_FIREBASE)] == "UNVERIFIED"
    assert validation_rows[("aws_s3", PLACEHOLDER_BUCKET)] == "UNVERIFIED"
    assert validation_rows[("supabase", HONEYPOT_SUPABASE)] == "HONEYPOT_SUSPECTED"
    stored_validation_rows = {
        (row["Type"], row["Asset"]): row["Stored Status"]
        for row in detail["sections"]["cloud_validation_results"]
    }
    assert stored_validation_rows[("firebase", WEAK_FIREBASE)] == "VALIDATED"
    assert stored_validation_rows[("aws_s3", PLACEHOLDER_BUCKET)] == "VALIDATED"
    return slug


def _assert_api_filters_stale_rows(slug: str) -> None:
    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get(f"/api/engagements/{slug}", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        detail = detail_resp.json()
        summary_resp = client.get(
            f"/api/engagements/{ENGAGEMENT_ID}/vuln-summary",
            headers=headers,
        )
        assert summary_resp.status_code == 200, summary_resp.text
        summary = summary_resp.json()

    assert _dashboard_targets(detail) == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }
    assert detail["severity_summary"]["HIGH"] == 2
    assert detail["counts"]["key_scanner_findings"] == 0
    assert detail["sections"]["key_scanner_findings"] == []
    assert summary["vulnerability_findings"].get("HIGH", 0) == 2
    _assert_graph_payload_excludes_stale_key_nodes(detail)


def _assert_deterministic_engine_removes_unstable_findings(db_path: Path) -> None:
    summary = DeterministicFindingEngine(db_path, ENGAGEMENT_ID).run()
    assert summary.active_findings == 2
    assert summary.severity_summary["HIGH"] == 2
    con = sqlite3.connect(db_path)
    try:
        targets = {
            row[0]
            for row in con.execute(
                """
                SELECT target_url
                FROM vulnerability_findings
                WHERE engagement_id=?
                """,
                (ENGAGEMENT_ID,),
            ).fetchall()
        }
    finally:
        con.close()
    assert targets == {
        f"aws_s3://{STABLE_BUCKET}",
        f"firebase://{STABLE_FIREBASE}",
    }


def _finding_targets(findings: list[dict[str, object]]) -> set[str]:
    return {str(finding.get("target_url") or "") for finding in findings}


def _inventory_status(
    inventory: list[dict[str, object]],
    asset_type: str,
    identifier: str,
) -> str:
    row = next(
        item
        for item in inventory
        if item.get("asset_type") == asset_type and item.get("identifier") == identifier
    )
    return str(row.get("validation_status") or "")


def _inventory_stored_status(
    inventory: list[dict[str, object]],
    asset_type: str,
    identifier: str,
) -> str:
    row = next(
        item
        for item in inventory
        if item.get("asset_type") == asset_type and item.get("identifier") == identifier
    )
    return str(row.get("stored_validation_status") or "")


def _csv_validation_status(
    rows: list[dict[str, str]],
    asset_type: str,
    identifier: str,
) -> str:
    row = next(
        item
        for item in rows
        if item.get("cloud_asset_type") == asset_type
        and item.get("cloud_identifier") == identifier
    )
    return row.get("validation_status") or ""


def _csv_stored_validation_status(
    rows: list[dict[str, str]],
    asset_type: str,
    identifier: str,
) -> str:
    row = next(
        item
        for item in rows
        if item.get("cloud_asset_type") == asset_type
        and item.get("cloud_identifier") == identifier
    )
    return row.get("stored_validation_status") or ""


def _dashboard_targets(detail_payload: dict[str, object]) -> set[str]:
    sections = detail_payload.get("sections")
    assert isinstance(sections, dict)
    rows = sections.get("vulnerability_findings")
    assert isinstance(rows, list)
    return {str(row.get("Target") or "") for row in rows if isinstance(row, dict)}


def _assert_graph_payload_excludes_stale_key_nodes(
    detail_payload: dict[str, object],
) -> None:
    graph_payload = detail_payload.get("graph_payload")
    assert isinstance(graph_payload, dict)
    nodes = graph_payload.get("nodes")
    assert isinstance(nodes, list)
    node_ids = {
        str(node.get("node_id") or "")
        for node in nodes
        if isinstance(node, dict)
    }
    assert "VULN::weak-key" not in node_ids
    assert "VULN::honeypot-key" not in node_ids
    assert "VULN::weak-key" not in graph_payload.get("critical_path_nodes", [])
