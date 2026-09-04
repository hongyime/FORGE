from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.deterministic_findings import DeterministicFindingEngine
from forge.phase6.report_synthesizer import ContextBuilder
from forge.reporting.dashboard import generate_dashboard
from forge.webui.app import create_app
from forge.webui.auth import mint_token

ENGAGEMENT_ID = 1001
SLUG = "engagement-1001-latest-validation-gate"


def _build_latest_validation_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
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
        con.executescript(
            """
            DROP TABLE cloud_validation_results;
            CREATE TABLE cloud_validation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER,
                asset_type TEXT,
                identifier TEXT,
                provider_identifier TEXT,
                validation_status TEXT,
                validation_method TEXT,
                http_status INTEGER,
                evidence TEXT,
                notes TEXT,
                checked_at TEXT
            );
            """
        )
        con.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (?, 'Latest Validation Gate', '["latest.example"]', 'ACTIVE', 'tester')
            """,
            (ENGAGEMENT_ID,),
        )
        con.execute(
            """
            INSERT INTO key_scanner_findings
                (engagement_id, domain, service, pattern_name, source_backend,
                 source_url, repo_name, key_redacted, validation_state,
                 validation_detail)
            VALUES
                (?, 'stale-firebase', 'firebase', 'firebase_api_key', 'artifact',
                 'app.js', 'app.js', 'AIza...STALE', 'ACTIVE',
                 'ACTIVE:manual_validated_note:no deterministic proof')
            """,
            (ENGAGEMENT_ID,),
        )
        con.executemany(
            """
            INSERT INTO cloud_validation_results
                (engagement_id, asset_type, identifier, validation_status,
                 validation_method, http_status, evidence, notes, checked_at)
            VALUES (?, 'firebase', 'stale-firebase', ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ENGAGEMENT_ID,
                    "VALIDATED",
                    "firebase_database_shallow_read",
                    200,
                    '{"users":1}',
                    "older live-data proof",
                    "2026-07-01T00:00:00Z",
                ),
                (
                    ENGAGEMENT_ID,
                    "UNVERIFIED",
                    "firebase_database_shallow_read",
                    403,
                    "latest blocked probe",
                    "latest validation no longer proves reportable access",
                    "2026-07-02T00:00:00Z",
                ),
            ],
        )
        con.commit()
    finally:
        con.close()
    return data_dir, reports_dir, db_path


def test_latest_cloud_validation_row_wins_for_linked_key_reportability(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(tmp_path / ".forge_data"))
    monkeypatch.setenv("FORGE_ENV", "test")
    monkeypatch.setenv("FORGE_WEB_SECRET_KEY", "s" * 64)
    monkeypatch.setenv("FORGE_WEB_AUTH", "jwt")
    data_dir, reports_dir, db_path = _build_latest_validation_fixture(tmp_path)

    finding_summary = DeterministicFindingEngine(db_path, ENGAGEMENT_ID).run()
    assert finding_summary.active_findings == 0
    assert finding_summary.severity_summary["HIGH"] == 0

    con = sqlite3.connect(db_path)
    try:
        finding_rows = con.execute(
            """
            SELECT vuln_type, title
            FROM vulnerability_findings
            WHERE engagement_id=?
            """,
            (ENGAGEMENT_ID,),
        ).fetchall()
    finally:
        con.close()
    assert finding_rows == []

    ctx = ContextBuilder(db_path, ENGAGEMENT_ID).build()
    assert ctx.osint.key_findings_count == 0
    assert ctx.exploits.finding_count == 0

    generate_dashboard(
        data_dir=data_dir,
        reports_dir=reports_dir,
        output_path=reports_dir / "dashboard.html",
    )
    detail_payload = json.loads(
        (reports_dir / "dashboard" / "data" / "engagements" / f"{SLUG}.json").read_text(
            encoding="utf-8"
        )
    )
    assert detail_payload["counts"]["key_scanner_findings"] == 0
    assert detail_payload["severity_summary"]["HIGH"] == 0
    assert detail_payload["sections"]["vulnerability_findings"] == []

    app = create_app()
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {mint_token('tester')}"}
        detail_resp = client.get(f"/api/engagements/{SLUG}", headers=headers)
        assert detail_resp.status_code == 200, detail_resp.text
        api_detail = detail_resp.json()
        summary_resp = client.get(
            f"/api/engagements/{ENGAGEMENT_ID}/vuln-summary",
            headers=headers,
        )
        assert summary_resp.status_code == 200, summary_resp.text
        api_summary = summary_resp.json()

    assert api_detail["counts"]["key_scanner_findings"] == 0
    assert api_detail["severity_summary"]["HIGH"] == 0
    assert api_summary["vulnerability_findings"].get("HIGH", 0) == 0
