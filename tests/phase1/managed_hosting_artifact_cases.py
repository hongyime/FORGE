from __future__ import annotations

import sqlite3
from pathlib import Path

from forge.engagement_orchestrator import ArtifactQueueProcessor
from tests.phase1.artifact_test_support import bootstrap_engagement


def run_managed_hosting_urls_as_provider_specific_cloud_assets(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    artifact_root = tmp_path / "artifact_hosted_cloud"
    artifact_root.mkdir()
    bootstrap_engagement(db_path)

    notes_path = artifact_root / "hosting-endpoints.txt"
    notes_path.write_text(
        """
        https://acme-preview.vercel.app/api/health
        https://acme-edge.netlify.app/status
        https://acme-amplify.amplifyapp.com/
        https://acmeportal.appspot.com/login
        https://us-central1-acmehub.cloudfunctions.net/ping
        https://api-prod-abc.a.run.app/health
        https://acme.github.io/status
        https://security.gitlab.io/report
        """.strip(),
        encoding="utf-8",
    )

    processor = ArtifactQueueProcessor(db_path, 1001)
    queued = processor.ingest_local_artifacts([artifact_root])
    summary = processor.process()

    assert queued >= 1
    assert summary.processed >= 1
    assert summary.discovered_seeds >= 8

    con = sqlite3.connect(db_path)
    try:
        cloud_assets = con.execute(
            """
            SELECT asset_type, identifier
            FROM cloud_assets
            WHERE engagement_id=1001
            ORDER BY asset_type, identifier
            """
        ).fetchall()
        assert ("vercel", "acme-preview") in cloud_assets
        assert ("netlify", "acme-edge") in cloud_assets
        assert ("amplify", "acme-amplify") in cloud_assets
        assert ("gcp_appspot", "acmeportal") in cloud_assets
        assert (
            "gcp_cloudfunctions",
            "https://us-central1-acmehub.cloudfunctions.net/ping",
        ) in cloud_assets
        assert ("gcp_cloud_run", "api-prod-abc.a.run.app") in cloud_assets
        assert ("github_pages", "acme.github.io") in cloud_assets
        assert ("gitlab_pages", "security.gitlab.io") in cloud_assets

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
        assert ("https://acme-preview.vercel.app/api/health", "url") in seeds
        assert ("https://acme-edge.netlify.app/status", "url") in seeds
        assert ("https://acme-amplify.amplifyapp.com/", "url") in seeds
        assert ("https://acmeportal.appspot.com/login", "url") in seeds
        assert ("https://us-central1-acmehub.cloudfunctions.net/ping", "url") in seeds
        assert ("https://api-prod-abc.a.run.app/health", "url") in seeds
        assert ("https://acme.github.io/status", "url") in seeds
        assert ("https://security.gitlab.io/report", "url") in seeds
        assert ("acme-preview.vercel.app", "subdomain") not in seeds
        assert ("vercel.app", "domain") not in seeds
        assert ("acme-edge.netlify.app", "subdomain") not in seeds
        assert ("netlify.app", "domain") not in seeds
        assert ("acme-amplify.amplifyapp.com", "subdomain") not in seeds
        assert ("amplifyapp.com", "domain") not in seeds
        assert ("acmeportal.appspot.com", "subdomain") not in seeds
        assert ("appspot.com", "domain") not in seeds
        assert ("us-central1-acmehub.cloudfunctions.net", "subdomain") not in seeds
        assert ("cloudfunctions.net", "domain") not in seeds
        assert ("api-prod-abc.a.run.app", "subdomain") not in seeds
        assert ("run.app", "domain") not in seeds
        assert ("acme.github.io", "subdomain") not in seeds
        assert ("github.io", "domain") not in seeds
        assert ("security.gitlab.io", "subdomain") not in seeds
        assert ("gitlab.io", "domain") not in seeds
    finally:
        con.close()
