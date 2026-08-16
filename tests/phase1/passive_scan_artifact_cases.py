from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_passive_scan_output_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_scan_outputs"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    nmap_path = artifact_root / "external-scan.nmap"
    nmap_path.write_text(
        """
        # Nmap scan report for portal.acme.example (203.0.113.10)
        443/tcp open https
        | http-title: Portal https://scan-portal.acme.example/login
        | owner: scan-owner@acme.example
        | firebase: https://scan-firebase.firebaseio.com
        | supabase_url: https://scanworkspace.supabase.co
        | supabase_key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNjYW53b3Jrc3BhY2UiLCJyb2xlIjoiYW5vbiJ9.signature777
        | bucket: s3://acme-scan-bucket/reports/latest.pdf
        """.strip(),
        encoding="utf-8",
    )

    bundle_path = artifact_root / "scan-exports.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "exports/web.gnmap",
            """
            Host: 203.0.113.20 (nested-scan.acme.example) Ports: 443/open/tcp//https//
            Script: nested-scan-owner@acme.example https://nested-scan.acme.example/report
            """.strip(),
        )
        zf.writestr(
            "exports/client.nessus",
            """
            <NessusClientData_v2>
              <Report>
                <ReportHost name="nessus.acme.example">
                  <ReportItem port="443" svc_name="https">
                    <plugin_output>
                      Contact nessus-owner@acme.example and review https://nessus.acme.example/finding
                    </plugin_output>
                  </ReportItem>
                </ReportHost>
              </Report>
            </NessusClientData_v2>
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.firebase_projects >= 1
    assert summary.supabase_configs >= 1
    assert summary.discovered_seeds >= 7

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "scan-owner@acme.example" in emails
        assert "nested-scan-owner@acme.example" in emails
        assert "nessus-owner@acme.example" in emails

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
        assert ("https://scan-portal.acme.example/login", "url") in seeds
        assert ("https://nested-scan.acme.example/report", "url") in seeds
        assert ("https://nessus.acme.example/finding", "url") in seeds
        assert ("scan-owner@acme.example", "email") in seeds
        assert ("nested-scan-owner@acme.example", "email") in seeds
        assert ("nessus-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-scan-bucket") in cloud_assets
        assert ("firebase", "scan-firebase") in cloud_assets
        assert ("supabase", "scanworkspace") in cloud_assets

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
        assert artifact_meta[nmap_path.resolve().as_posix()]["format"] == "nmap"
        assert artifact_meta[nmap_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
