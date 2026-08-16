from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import (
    ArtifactQueueProcessor,
    _classify_remote_artifact_url,
    _suffix_from_content_type,
)
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_windows_event_trace_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_windows_events"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    evtx_payload = "\n".join(
        [
            "event-owner@acme.example",
            "https://event-log.acme.example/security",
            "https://event-firebase.firebaseio.com",
            "https://eventvault.supabase.co/rest/v1/events",
            "s3://acme-event-bucket/logs/security.evtx",
            "gs://acme-event-gcs/logs/security.evtx",
        ]
    ).encode("utf-16-le")
    evtx_path = artifact_root / "security.evtx"
    evtx_path.write_bytes(b"ElfFile\x00\x00\x00\x00" + evtx_payload)

    etl_path = artifact_root / "network.etl"
    etl_path.write_bytes(
        b"MsTrace\x00"
        b"etl-owner@acme.example\x00"
        b"https://etl.acme.example/session\x00"
        b"https://etl-firebase.firebaseio.com\x00"
    )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/security.evtx") == "document"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/network.etl?download=1")
        == "document"
    )
    assert _suffix_from_content_type("application/x-ms-evtx") == ".evtx"
    assert _suffix_from_content_type("application/vnd.ms-eventlog") == ".evtx"
    assert _suffix_from_content_type("application/x-ms-trace-log") == ".etl"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 2
    assert summary.processed >= 2
    assert summary.discovered_seeds >= 4

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "event-owner@acme.example" in emails
        assert "etl-owner@acme.example" in emails

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
        assert ("event-owner@acme.example", "email") in seeds
        assert ("etl-owner@acme.example", "email") in seeds
        assert ("https://event-log.acme.example/security", "url") in seeds
        assert ("https://etl.acme.example/session", "url") in seeds
        assert ("https://eventvault.supabase.co/rest/v1/events", "url") in seeds
        assert ("event-log.acme.example", "subdomain") in seeds
        assert ("etl.acme.example", "subdomain") in seeds
        assert ("eventvault.supabase.co", "subdomain") not in seeds
        assert ("supabase.co", "domain") not in seeds

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
        assert ("aws_s3", "acme-event-bucket") in cloud_assets
        assert ("firebase", "event-firebase") in cloud_assets
        assert ("firebase", "etl-firebase") in cloud_assets
        assert ("gcs", "acme-event-gcs") in cloud_assets
        assert ("supabase", "eventvault") in cloud_assets

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
        assert artifact_meta[evtx_path.resolve().as_posix()]["format"] == "evtx"
        assert artifact_meta[evtx_path.resolve().as_posix()]["parser"] == "document"
        assert artifact_meta[evtx_path.resolve().as_posix()]["payload_count"] >= 1
        assert artifact_meta[etl_path.resolve().as_posix()]["format"] == "etl"
        assert artifact_meta[etl_path.resolve().as_posix()]["parser"] == "document"
        assert artifact_meta[etl_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()


def run_windows_execution_history_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_windows_execution_history"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    prefetch_path = artifact_root / "ACME-PORTAL.EXE-12345678.pf"
    prefetch_path.write_bytes(
        b"SCCA\x11\x00\x00\x00"
        b"prefetch-owner@acme.example\x00"
        b"https://prefetch.acme.example/portal\x00"
        b"https://prefetch-firebase.firebaseio.com\x00"
        b"https://prefetchvault.supabase.co/rest/v1/runs\x00"
        b"s3://acme-prefetch-bucket/runs/ACME-PORTAL.pf\x00"
    )

    automatic_path = artifact_root / "team.automaticDestinations-ms"
    automatic_path.write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        b"jumplist-owner@acme.example\x00"
        b"https://jumplist.acme.example/recent\x00"
        b"https://jumplist-firebase.firebaseio.com\x00"
        b"gs://acme-jumplist-gcs/recent/team.automaticDestinations-ms\x00"
    )

    custom_path = artifact_root / "ops.customDestinations-ms"
    custom_path.write_bytes(
        b"CSTMDEST\x00"
        b"custom-owner@acme.example\x00"
        b"https://custom-jumplist.acme.example/ops\x00"
        b"https://customvault.supabase.co/rest/v1/jumplist\x00"
    )

    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/ACME-PORTAL.EXE-12345678.pf")
        == "document"
    )
    assert (
        _classify_remote_artifact_url(
            "https://downloads.acme.example/team.automaticDestinations-ms"
        )
        == "document"
    )
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/ops.customDestinations-ms")
        == "document"
    )
    assert _suffix_from_content_type("application/x-ms-prefetch") == ".pf"
    assert _suffix_from_content_type("application/x-ms-jumplist") == ".automaticdestinations-ms"
    assert _suffix_from_content_type("application/x-ms-destinations") == ".customdestinations-ms"

    processor = ArtifactQueueProcessor(db_path, 1001, max_workers=4)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 3
    assert summary.processed >= 3
    assert summary.discovered_seeds >= 6

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        assert "prefetch-owner@acme.example" in emails
        assert "jumplist-owner@acme.example" in emails
        assert "custom-owner@acme.example" in emails

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
        assert ("prefetch-owner@acme.example", "email") in seeds
        assert ("jumplist-owner@acme.example", "email") in seeds
        assert ("custom-owner@acme.example", "email") in seeds
        assert ("https://prefetch.acme.example/portal", "url") in seeds
        assert ("https://jumplist.acme.example/recent", "url") in seeds
        assert ("https://custom-jumplist.acme.example/ops", "url") in seeds
        assert ("https://prefetchvault.supabase.co/rest/v1/runs", "url") in seeds
        assert ("https://customvault.supabase.co/rest/v1/jumplist", "url") in seeds
        assert ("prefetch.acme.example", "subdomain") in seeds
        assert ("jumplist.acme.example", "subdomain") in seeds
        assert ("custom-jumplist.acme.example", "subdomain") in seeds
        assert ("prefetchvault.supabase.co", "subdomain") not in seeds
        assert ("customvault.supabase.co", "subdomain") not in seeds

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
        assert ("aws_s3", "acme-prefetch-bucket") in cloud_assets
        assert ("firebase", "jumplist-firebase") in cloud_assets
        assert ("firebase", "prefetch-firebase") in cloud_assets
        assert ("gcs", "acme-jumplist-gcs") in cloud_assets
        assert ("supabase", "customvault") in cloud_assets
        assert ("supabase", "prefetchvault") in cloud_assets

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
        assert artifact_meta[prefetch_path.resolve().as_posix()]["format"] == "pf"
        assert artifact_meta[prefetch_path.resolve().as_posix()]["parser"] == "document"
        assert artifact_meta[prefetch_path.resolve().as_posix()]["payload_count"] >= 1
        assert (
            artifact_meta[automatic_path.resolve().as_posix()]["format"]
            == "automaticdestinations-ms"
        )
        assert artifact_meta[automatic_path.resolve().as_posix()]["parser"] == "document"
        assert artifact_meta[custom_path.resolve().as_posix()]["format"] == "customdestinations-ms"
        assert artifact_meta[custom_path.resolve().as_posix()]["parser"] == "document"
    finally:
        con.close()
