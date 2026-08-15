from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_log_and_trace_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_logs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    log_path = artifact_root / "application.log"
    log_path.write_text(
        """
        2026-07-14T10:00:01Z owner=log-owner@acme.example
        request_url=https://logs.acme.example/api/session
        firebase=https://log-firebase.firebaseio.com
        supabase_url=https://logworkspace.supabase.co
        supabase_key=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxvZ3dvcmtzcGFjZSIsInJvbGUiOiJhbm9uIn0.signature666
        bucket=s3://acme-log-bucket/reports/latest.pdf
        """.strip(),
        encoding="utf-8",
    )

    bundle_path = artifact_root / "log-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "logs/error.trace",
            """
            trace_owner=trace-owner@acme.example
            trace_url=https://trace.acme.example/error/42
            """.strip(),
        )
        zf.writestr(
            "logs/access_log",
            """
            access_owner=access-log-owner@acme.example
            access_url=https://access-log.acme.example/request/7
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 6

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "log-owner@acme.example" in emails
        assert "trace-owner@acme.example" in emails
        assert "access-log-owner@acme.example" in emails

        seeds = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT seed_value, seed_type
                FROM engagement_seeds
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert ("https://logs.acme.example/api/session", "url") in seeds
        assert ("https://trace.acme.example/error/42", "url") in seeds
        assert ("https://access-log.acme.example/request/7", "url") in seeds
        assert ("log-owner@acme.example", "email") in seeds
        assert ("trace-owner@acme.example", "email") in seeds
        assert ("access-log-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-log-bucket") in cloud_assets
        assert ("firebase", "log-firebase") in cloud_assets
        assert ("supabase", "logworkspace") in cloud_assets

        artifact_meta = {
            row[0]: json.loads(str(row[1] or "{}"))
            for row in con.execute(
                """
                SELECT source_url, metadata_json
                FROM artifact_queue
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
        assert artifact_meta[log_path.resolve().as_posix()]["format"] == "log"
        assert artifact_meta[log_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
