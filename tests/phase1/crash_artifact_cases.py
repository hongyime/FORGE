from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_crash_diagnostic_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_crash_diagnostics"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    crash_path = artifact_root / "incident.crash"
    crash_path.write_text(
        """
        Incident Identifier: ACME-CRASH-1
        Reporter: crash-owner@acme.example
        Crashed Thread: 0
        Endpoint: https://crash.acme.example/reports/1
        Firebase: https://crash-firebase.firebaseio.com
        Archive: s3://acme-crash-bucket/reports/incident.crash
        """.strip(),
        encoding="utf-8",
    )

    ips_path = artifact_root / "session.ips"
    ips_path.write_text(
        json.dumps(
            {
                "bug_type": "309",
                "incident": "ACME-IPS-1",
                "metadata": {
                    "owner": "ips-owner@acme.example",
                    "url": "https://ips.acme.example/session",
                    "supabase": "https://ipsvault.supabase.co/rest/v1",
                    "archive": "gs://acme-ips-gcs/sessions/latest.ips",
                },
            }
        ),
        encoding="utf-8",
    )

    stacktrace_path = artifact_root / "app.stacktrace"
    stacktrace_path.write_text(
        """
        java.lang.RuntimeException: failed request
            at com.acme.Client.fetch(Client.kt:42)
        owner=stacktrace-owner@acme.example
        request=https://stacktrace.acme.example/api/fail
        firebase=https://stacktrace-firebase.firebaseio.com
        """.strip(),
        encoding="utf-8",
    )

    tombstone_path = artifact_root / "tombstone_00"
    tombstone_path.write_text(
        """
        *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
        signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)
        owner=tombstone-owner@acme.example
        endpoint=https://tombstone.acme.example/native
        azure=https://tombstoneblob.blob.core.windows.net/public/tombstone_00
        """.strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "diagnostics.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "android/main.anr",
            """
            ANR in com.acme.app
            Subject: anr-owner@acme.example
            Trace: https://anr.acme.example/trace/7
            Supabase: https://anrvault.supabase.co/rest/v1
            """.strip(),
        )
        zf.writestr(
            "native/crash.tombstone",
            """
            process: com.acme.app
            owner=native-tombstone-owner@acme.example
            symbol_server=https://native-tombstone.acme.example/symbols
            bucket=s3://acme-native-tombstone-bucket/symbols/latest.zip
            """.strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.firebase_projects >= 2
    assert summary.discovered_seeds >= 12

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "crash-owner@acme.example",
            "ips-owner@acme.example",
            "stacktrace-owner@acme.example",
            "tombstone-owner@acme.example",
            "anr-owner@acme.example",
            "native-tombstone-owner@acme.example",
        }:
            assert expected_email in emails

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
        for expected_url in {
            "https://crash.acme.example/reports/1",
            "https://ips.acme.example/session",
            "https://stacktrace.acme.example/api/fail",
            "https://tombstone.acme.example/native",
            "https://anr.acme.example/trace/7",
            "https://native-tombstone.acme.example/symbols",
        }:
            assert (expected_url, "url") in seeds
        assert ("crash-owner@acme.example", "email") in seeds
        assert ("tombstone-owner@acme.example", "email") in seeds
        assert ("native-tombstone-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-crash-bucket") in cloud_assets
        assert ("aws_s3", "acme-native-tombstone-bucket") in cloud_assets
        assert ("azure_blob", "tombstoneblob/public") in cloud_assets
        assert ("firebase", "crash-firebase") in cloud_assets
        assert ("firebase", "stacktrace-firebase") in cloud_assets
        assert ("gcs", "acme-ips-gcs") in cloud_assets
        assert ("supabase", "anrvault") in cloud_assets
        assert ("supabase", "ipsvault") in cloud_assets

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
        assert artifact_meta[crash_path.resolve().as_posix()]["format"] == "crash"
        assert artifact_meta[ips_path.resolve().as_posix()]["format"] == "ips"
        assert artifact_meta[stacktrace_path.resolve().as_posix()]["format"] == "stacktrace"
        assert artifact_meta[tombstone_path.resolve().as_posix()]["format"] == "tombstone_00"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 2
    finally:
        con.close()
