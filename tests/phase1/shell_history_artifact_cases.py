from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _artifact_format_label,
    _classify_artifact_name,
    _classify_remote_artifact_url,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_shell_history_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_shell_history"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    bash_path = artifact_root / ".bash_history"
    bash_path.write_text(
        "\n".join(
            [
                "curl https://shell-history.acme.example/login",
                "export OWNER=shell-owner@acme.example",
                "firebase=https://shell-history-firebase.firebaseio.com",
                "supabase=https://shellhistoryvault.supabase.co/rest/v1/events",
                "aws s3 ls s3://acme-shell-history-bucket/logs/",
            ]
        ),
        encoding="utf-8",
    )

    powershell_path = artifact_root / "ConsoleHost_history.txt"
    powershell_path.write_text(
        "\n".join(
            [
                "Invoke-WebRequest https://pshistory.acme.example/health",
                "Write-Host pshistory-owner@acme.example",
                "gsutil ls gs://acme-pshistory-gcs/reports",
            ]
        ),
        encoding="utf-8",
    )

    archive_path = artifact_root / "history-bundle.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr(
            "home/operator/.zsh_history",
            "\n".join(
                [
                    ": 1700000000:0;curl https://zsh-history.acme.example/api",
                    "echo zsh-owner@acme.example",
                    "open https://zsh-firebase.firebaseio.com",
                ]
            ),
        )

    assert _classify_artifact_name(bash_path) == "config"
    assert (
        _classify_remote_artifact_url("https://repo.acme.example/home/.bash_history?raw=1")
        == "config"
    )
    assert (
        _classify_remote_artifact_url("https://repo.acme.example/ConsoleHost_history.txt")
        == "config"
    )
    assert _artifact_format_label(bash_path) == "shell-history"
    assert _artifact_format_label(powershell_path) == "shell-history"
    assert _artifact_format_label("42-.zsh_history") == "shell-history"
    assert _artifact_format_label("History") == "history"

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 7

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "shell-owner@acme.example" in emails
        assert "pshistory-owner@acme.example" in emails
        assert "zsh-owner@acme.example" in emails

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
        assert ("https://shell-history.acme.example/login", "url") in seeds
        assert ("https://pshistory.acme.example/health", "url") in seeds
        assert ("https://zsh-history.acme.example/api", "url") in seeds
        assert ("shell-owner@acme.example", "email") in seeds
        assert ("pshistory-owner@acme.example", "email") in seeds
        assert ("zsh-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-shell-history-bucket") in cloud_assets
        assert ("firebase", "shell-history-firebase") in cloud_assets
        assert ("firebase", "zsh-firebase") in cloud_assets
        assert ("gcs", "acme-pshistory-gcs") in cloud_assets
        assert ("supabase", "shellhistoryvault") in cloud_assets

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
        assert artifact_meta[bash_path.resolve().as_posix()]["format"] == "shell-history"
        assert artifact_meta[powershell_path.resolve().as_posix()]["format"] == "shell-history"
        assert artifact_meta[archive_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[archive_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
