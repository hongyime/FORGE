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


def run_shortcut_link_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_shortcuts"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    url_path = artifact_root / "portal.url"
    url_path.write_text(
        "\n".join(
            [
                "[InternetShortcut]",
                "URL=https://shortcut.acme.example/portal",
                "Owner=shortcut-owner@acme.example",
                "Firebase=https://shortcut-firebase.firebaseio.com",
                "Supabase=https://shortcutvault.supabase.co/rest/v1/shortcuts",
            ]
        ),
        encoding="utf-8",
    )

    website_path = artifact_root / "portal.website"
    website_path.write_text(
        "\n".join(
            [
                "[InternetShortcut]",
                "URL=https://website.acme.example/home",
                "Owner=website-owner@acme.example",
                "Firebase=https://website-firebase.firebaseio.com",
            ]
        ),
        encoding="utf-8",
    )

    webloc_path = artifact_root / "team.webloc"
    webloc_path.write_text(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
          <dict>
            <key>URL</key>
            <string>https://webloc.acme.example/team</string>
            <key>Owner</key>
            <string>webloc-owner@acme.example</string>
            <key>Mirror</key>
            <string>gs://acme-webloc-gcs/shortcuts/team.webloc</string>
          </dict>
        </plist>
        """,
        encoding="utf-8",
    )

    desktop_path = artifact_root / "launch.desktop"
    desktop_path.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Link",
                "URL=https://desktop.acme.example/app",
                "Comment=desktop-owner@acme.example https://desktop-firebase.firebaseio.com",
                "X-Acme-Archive=s3://acme-desktop-bucket/shortcuts/launch.desktop",
            ]
        ),
        encoding="utf-8",
    )

    lnk_path = artifact_root / "legacy.lnk"
    lnk_path.write_bytes(
        b"L\x00\x00\x00\x01\x14\x02\x00"
        b"lnk-owner@acme.example\x00"
        b"https://lnk.acme.example/legacy\x00"
        b"https://lnk-firebase.firebaseio.com\x00"
        b"https://lnkvault.supabase.co/rest/v1/shortcuts\x00"
    )

    assert _classify_remote_artifact_url("https://downloads.acme.example/portal.url") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/portal.website") == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/team.webloc") == "config"
    assert (
        _classify_remote_artifact_url("https://downloads.acme.example/launch.desktop") == "config"
    )
    assert _classify_remote_artifact_url("https://downloads.acme.example/legacy.lnk") == "document"
    assert _suffix_from_content_type("application/x-ms-shortcut") == ".lnk"
    assert _suffix_from_content_type("application/x-mswinurl") == ".url"
    assert _suffix_from_content_type("application/internet-shortcut") == ".url"
    assert _suffix_from_content_type("application/x-desktop") == ".desktop"
    assert _suffix_from_content_type("application/x-apple-webloc") == ".webloc"

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
        assert "shortcut-owner@acme.example" in emails
        assert "website-owner@acme.example" in emails
        assert "webloc-owner@acme.example" in emails
        assert "desktop-owner@acme.example" in emails
        assert "lnk-owner@acme.example" in emails

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
        assert ("shortcut-owner@acme.example", "email") in seeds
        assert ("website-owner@acme.example", "email") in seeds
        assert ("webloc-owner@acme.example", "email") in seeds
        assert ("desktop-owner@acme.example", "email") in seeds
        assert ("lnk-owner@acme.example", "email") in seeds
        assert ("https://shortcut.acme.example/portal", "url") in seeds
        assert ("https://website.acme.example/home", "url") in seeds
        assert ("https://webloc.acme.example/team", "url") in seeds
        assert ("https://desktop.acme.example/app", "url") in seeds
        assert ("https://lnk.acme.example/legacy", "url") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-desktop-bucket") in cloud_assets
        assert ("firebase", "desktop-firebase") in cloud_assets
        assert ("firebase", "lnk-firebase") in cloud_assets
        assert ("firebase", "shortcut-firebase") in cloud_assets
        assert ("firebase", "website-firebase") in cloud_assets
        assert ("gcs", "acme-webloc-gcs") in cloud_assets
        assert ("supabase", "lnkvault") in cloud_assets
        assert ("supabase", "shortcutvault") in cloud_assets

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
        assert artifact_meta[url_path.resolve().as_posix()]["format"] == "url"
        assert artifact_meta[website_path.resolve().as_posix()]["format"] == "website"
        assert artifact_meta[webloc_path.resolve().as_posix()]["format"] == "webloc"
        assert artifact_meta[desktop_path.resolve().as_posix()]["format"] == "desktop"
        assert artifact_meta[lnk_path.resolve().as_posix()]["format"] == "lnk"
        assert artifact_meta[lnk_path.resolve().as_posix()]["payload_count"] >= 1
    finally:
        con.close()
