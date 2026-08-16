from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_dump_binary_string_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_dump_binaries"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    rdb_path = artifact_root / "dump.rdb"
    rdb_path.write_bytes(
        b"REDIS0011\x00"
        b"redis-owner@acme.example\x00"
        b"https://cache.acme.example/session\x00"
        b"https://redis-dump-firebase.firebaseio.com\x00"
        b"https://redisdump.supabase.co/rest/v1/cache\x00"
        b"s3://acme-redis-dump-bucket/prod/dump.rdb\x00"
    )

    hprof_path = artifact_root / "prod.hprof"
    hprof_path.write_bytes(
        b"JAVA PROFILE 1.0.2\x00hprof-owner@acme.example\x00gs://acme-hprof-gcs/prod/prod.hprof\x00"
    )

    pprof_path = artifact_root / "cpu.pprof"
    pprof_path.write_bytes(
        b"\x1f\x8bpprof\x00"
        b"pprof-owner@acme.example\x00"
        b"https://pprof.acme.example/debug\x00"
        b"https://pprof-firebase.firebaseio.com\x00"
    )

    profile_path = artifact_root / "profile.cpuprofile"
    profile_path.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "callFrame": {
                            "url": "https://profile.acme.example/app.js",
                            "functionName": "profile-owner@acme.example",
                        }
                    }
                ],
                "metadata": {
                    "firebase": "https://profile-firebase.firebaseio.com",
                },
            }
        ),
        encoding="utf-8",
    )

    bundle_path = artifact_root / "database-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as zf:
        zf.writestr(
            "leveldb/000123.ldb",
            (
                b"nested-leveldb@acme.example\x00"
                b"https://nested-leveldb.acme.example/pivot\x00"
                b"https://nested-leveldb-firebase.firebaseio.com\x00"
            ),
        )
        zf.writestr(
            "profiles/node.heapdump",
            (
                b"heapdump-owner@acme.example\x00"
                b"https://heapdump.acme.example/snapshot\x00"
                b"gs://acme-heapdump-gcs/prod/node.heapdump\x00"
            ),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 5
    assert summary.processed >= 5
    assert summary.discovered_seeds >= 10

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "redis-owner@acme.example" in emails
        assert "hprof-owner@acme.example" in emails
        assert "pprof-owner@acme.example" in emails
        assert "profile-owner@acme.example" in emails
        assert "nested-leveldb@acme.example" in emails
        assert "heapdump-owner@acme.example" in emails

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
        assert ("redis-owner@acme.example", "email") in seeds
        assert ("hprof-owner@acme.example", "email") in seeds
        assert ("pprof-owner@acme.example", "email") in seeds
        assert ("profile-owner@acme.example", "email") in seeds
        assert ("nested-leveldb@acme.example", "email") in seeds
        assert ("heapdump-owner@acme.example", "email") in seeds
        assert ("https://cache.acme.example/session", "url") in seeds
        assert ("https://pprof.acme.example/debug", "url") in seeds
        assert ("https://profile.acme.example/app.js", "url") in seeds
        assert ("https://nested-leveldb.acme.example/pivot", "url") in seeds
        assert ("https://heapdump.acme.example/snapshot", "url") in seeds
        assert ("https://redisdump.supabase.co/rest/v1/cache", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-redis-dump-bucket") in cloud_assets
        assert ("firebase", "redis-dump-firebase") in cloud_assets
        assert ("firebase", "pprof-firebase") in cloud_assets
        assert ("firebase", "profile-firebase") in cloud_assets
        assert ("firebase", "nested-leveldb-firebase") in cloud_assets
        assert ("gcs", "acme-heapdump-gcs") in cloud_assets
        assert ("gcs", "acme-hprof-gcs") in cloud_assets
        assert ("supabase", "redisdump") in cloud_assets

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
        assert artifact_meta[rdb_path.resolve().as_posix()]["format"] == "rdb"
        assert artifact_meta[rdb_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[hprof_path.resolve().as_posix()]["format"] == "hprof"
        assert artifact_meta[hprof_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[pprof_path.resolve().as_posix()]["format"] == "pprof"
        assert artifact_meta[pprof_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[profile_path.resolve().as_posix()]["format"] == "cpuprofile"
        assert artifact_meta[profile_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[bundle_path.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[bundle_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
