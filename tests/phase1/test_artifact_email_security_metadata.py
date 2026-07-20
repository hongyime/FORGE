from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def test_mta_sts_mx_hosts_become_recursive_host_seeds(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "email_security_metadata"
    artifact_root.mkdir()
    bootstrap_engagement(db_path, name="Email Security Metadata Test")

    (artifact_root / "mta-sts.txt").write_text(
        """
        version: STSv1
        mode: enforce
        mx: mail.acme.example
        mx: *.backup.acme.example
        mx: localhost
        contact: mta-owner@acme.example
        policy_url: https://mail.acme.example/.well-known/mta-sts.txt
        supabase: https://mtastsvault.supabase.co
        """,
        encoding="utf-8",
    )
    (artifact_root / "notes.txt").write_text(
        """
        mx: generic.acme.example
        contact: notes-owner@acme.example
        """,
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued == 2
    assert summary.processed == 2

    con = sqlite3.connect(db_path)
    try:
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
        cloud_assets = {
            (row[0], row[1])
            for row in con.execute(
                """
                SELECT asset_type, identifier
                FROM cloud_assets
                WHERE engagement_id=1001
                """
            ).fetchall()
        }
    finally:
        con.close()

    assert ("mta-owner@acme.example", "email") in seeds
    assert ("notes-owner@acme.example", "email") in seeds
    assert ("https://mail.acme.example/.well-known/mta-sts.txt", "url") in seeds
    assert ("mail.acme.example", "subdomain") in seeds
    assert ("backup.acme.example", "subdomain") in seeds
    assert ("acme.example", "domain") in seeds
    assert ("generic.acme.example", "subdomain") not in seeds
    assert ("supabase", "mtastsvault") in cloud_assets
