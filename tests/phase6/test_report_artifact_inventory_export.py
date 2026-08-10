from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from forge.db.schema import apply_schema
from forge.phase6.report_synthesizer import ContextBuilder, ReportSynthesizer


ENGAGEMENT_ID = 1


def _artifact_inventory_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "artifact_inventory.db"
    con = sqlite3.connect(db_path)
    try:
        apply_schema(con)
        con.execute(
            """
            INSERT INTO engagements
                (id, name, scope_json, status, operator, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ENGAGEMENT_ID,
                "Artifact Inventory Assessment",
                '["acme.example"]',
                "ACTIVE",
                "analyst_01",
                "{}",
            ),
        )
        con.execute(
            """
            INSERT INTO artifact_queue
                (engagement_id, source_url, local_path, artifact_type,
                 discovered_from, status, sha256, notes, metadata_json,
                 queued_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ENGAGEMENT_ID,
                "https://downloads.acme.example/mobile/app.apk?token=raw-secret",
                r"C:\Users\bryan\Downloads\raw-secret\app.apk",
                "apk",
                "https://www.acme.example/downloads",
                "parsed",
                "a" * 64,
                "parsed config secret=raw-secret",
                json.dumps(
                    {
                        "parser": "apk_static_extract",
                        "format": "apk",
                        "payload_count": 4,
                        "downloaded_from_remote": True,
                        "source_url": (
                            "https://downloads.acme.example/mobile/app.apk?api_key=raw-secret"
                        ),
                        "local_path": r"C:\Users\bryan\Downloads\raw-secret\app.apk",
                        "token": "never-export-this-token",
                        "nested": {
                            "client_secret": "never-export-this-secret",
                            "owner": "mobile-owner@acme.example",
                            "callback": "https://api.acme.example/cb?token=raw-secret",
                        },
                    },
                    sort_keys=True,
                ),
                "2026-07-24T01:00:00",
                "2026-07-24T01:02:00",
            ),
        )
        con.commit()
    finally:
        con.close()
    return db_path


def test_phase6_exports_scrubbed_artifact_inventory(tmp_path: Path) -> None:
    db_path = _artifact_inventory_db(tmp_path)
    synth = ReportSynthesizer(
        db_path=db_path,
        output_dir=tmp_path,
        provider="template",
        assume_yes=True,
    )

    report_path = synth.generate(ENGAGEMENT_ID)
    payload = json.loads(report_path.with_suffix(".json").read_text(encoding="utf-8"))
    csv_rows = list(csv.DictReader(report_path.with_suffix(".csv").open(encoding="utf-8")))
    ctx = ContextBuilder(db_path, ENGAGEMENT_ID).build()
    raw_rows = ReportSynthesizer._raw_export_csv_rows(ctx)

    artifact_context = payload["context"]["artifact_inventory"][0]
    artifact_rows = [row for row in csv_rows if row["record_type"] == "artifact"]
    raw_artifact_rows = [row for row in raw_rows if row["record_type"] == "artifact"]
    exported_blob = json.dumps(payload["context"], sort_keys=True) + json.dumps(csv_rows)

    assert artifact_context["source_url"] == "https://downloads.acme.example/mobile/app.apk"
    assert artifact_context["artifact_type"] == "apk"
    assert artifact_context["status"] == "parsed"
    assert artifact_context["sha256"] == "a" * 64
    assert artifact_context["metadata"]["parser"] == "apk_static_extract"
    assert artifact_context["metadata"]["nested"]["owner"] == "mobile-owner@acme.example"
    assert "local_path" not in artifact_context["metadata"]
    assert "token" not in artifact_context["metadata"]
    assert "client_secret" not in artifact_context["metadata"]["nested"]

    assert len(artifact_rows) == 1
    assert artifact_rows[0]["artifact_source_url"] == artifact_context["source_url"]
    assert artifact_rows[0]["artifact_status"] == "parsed"
    assert "parser=apk_static_extract" in artifact_rows[0]["artifact_metadata_summary"]
    assert raw_artifact_rows[0]["artifact_source_url"] == artifact_context["source_url"]

    assert "raw-secret" not in exported_blob
    assert "never-export-this" not in exported_blob
    assert r"C:\Users\bryan\Downloads" not in exported_blob
