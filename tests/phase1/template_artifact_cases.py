from __future__ import annotations

import json
import sqlite3
import zipfile
from pathlib import Path
from textwrap import dedent
from typing import Callable

from forge.engagement_orchestrator import ArtifactQueueProcessor


def run_queue_processor_extracts_template_text_artifacts(
    tmp_path: Path,
    bootstrap_engagement: Callable[[Path], None],
) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_template_text"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    helm_tpl_path = artifact_root / "deployment.yaml.tpl"
    helm_tpl_path.write_text(
        dedent(
            """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              annotations:
                owner: template-owner@acme.example
                dashboard: https://template.acme.example/deploy
                firebase: https://template-firebase.firebaseio.com
                supabase: https://templatevault.supabase.co/rest/v1
            """
        ).strip(),
        encoding="utf-8",
    )

    jinja_path = artifact_root / "secrets.env.j2"
    jinja_path.write_text(
        dedent(
            """
            SUPPORT_EMAIL=jinja-owner@acme.example
            STATUS_URL=https://jinja.acme.example/status
            EXPORT_BUCKET=s3://acme-template-bucket/exports/latest.json
            GCS_ARCHIVE=gs://acme-template-gcs/archive/latest.json
            """
        ).strip(),
        encoding="utf-8",
    )

    go_template_path = artifact_root / "values.gotmpl"
    go_template_path.write_text(
        dedent(
            """
            owner: gotmpl-owner@acme.example
            portal: https://gotmpl.acme.example/values
            """
        ).strip(),
        encoding="utf-8",
    )

    nested_bundle = artifact_root / "template-bundle.zip"
    with zipfile.ZipFile(nested_bundle, "w") as zf:
        zf.writestr(
            "templates/configmap.yaml.mustache",
            dedent(
                """
                owner: mustache-owner@acme.example
                url: https://mustache.acme.example/config
                """
            ).strip(),
        )
        zf.writestr(
            "templates/ingress.hbs",
            dedent(
                """
                owner={{hbs-owner@acme.example}}
                endpoint=https://hbs.acme.example/ingress
                """
            ).strip(),
        )
        zf.writestr(
            "views/deploy.erb",
            dedent(
                """
                owner=<%= "erb-owner@acme.example" %>
                callback=https://erb.acme.example/callback
                firebase=https://erb-firebase.firebaseio.com
                """
            ).strip(),
        )
        zf.writestr(
            "views/service.ejs",
            dedent(
                """
                owner=<%= "ejs-owner@acme.example" %>
                portal=https://ejs.acme.example/service
                """
            ).strip(),
        )
        zf.writestr(
            "templates/status.liquid",
            dedent(
                """
                owner: liquid-owner@acme.example
                status_url: https://liquid.acme.example/status
                """
            ).strip(),
        )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 4
    assert summary.processed >= 4
    assert summary.discovered_seeds >= 15

    con = sqlite3.connect(db_path)
    try:
        emails = {
            row[0]
            for row in con.execute("SELECT email FROM emails WHERE engagement_id=1001").fetchall()
        }
        for expected_email in {
            "template-owner@acme.example",
            "jinja-owner@acme.example",
            "gotmpl-owner@acme.example",
            "mustache-owner@acme.example",
            "hbs-owner@acme.example",
            "erb-owner@acme.example",
            "ejs-owner@acme.example",
            "liquid-owner@acme.example",
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
            "https://template.acme.example/deploy",
            "https://jinja.acme.example/status",
            "https://gotmpl.acme.example/values",
            "https://mustache.acme.example/config",
            "https://hbs.acme.example/ingress",
            "https://erb.acme.example/callback",
            "https://ejs.acme.example/service",
            "https://liquid.acme.example/status",
        }:
            assert (expected_url, "url") in seeds
        assert ("template-owner@acme.example", "email") in seeds
        assert ("jinja-owner@acme.example", "email") in seeds
        assert ("liquid-owner@acme.example", "email") in seeds

        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("aws_s3", "acme-template-bucket") in cloud_assets
        assert ("firebase", "template-firebase") in cloud_assets
        assert ("firebase", "erb-firebase") in cloud_assets
        assert ("gcs", "acme-template-gcs") in cloud_assets
        assert ("supabase", "templatevault") in cloud_assets

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
        assert artifact_meta[helm_tpl_path.resolve().as_posix()]["format"] == "tpl"
        assert artifact_meta[jinja_path.resolve().as_posix()]["format"] == "j2"
        assert artifact_meta[go_template_path.resolve().as_posix()]["format"] == "gotmpl"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["format"] == "zip"
        assert artifact_meta[nested_bundle.resolve().as_posix()]["payload_count"] >= 5
    finally:
        con.close()
